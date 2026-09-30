package server

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/rand"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/kguardian-dev/kguardian/cataloger/internal/child"
	"github.com/kguardian-dev/kguardian/cataloger/internal/protocol"
)

// The test binary doubles as the scan child: the server re-executes it
// with KG_SERVER_TEST_CHILD set and the child subcommand last.
func TestMain(m *testing.M) {
	if os.Getenv("KG_SERVER_TEST_CHILD") == "1" {
		if ms, _ := strconv.Atoi(os.Getenv("KG_TEST_CHILD_SLEEP_MS")); ms > 0 && os.Args[len(os.Args)-1] == "scan-child" {
			time.Sleep(time.Duration(ms) * time.Millisecond)
		}
		switch os.Args[len(os.Args)-1] {
		case "scan-child":
			os.Exit(child.Main())
		case "probe-caps":
			os.Exit(child.Probe())
		case "clean-tmp":
			os.Exit(child.CleanTmp())
		}
		os.Exit(2)
	}
	os.Exit(m.Run())
}

// worldDir is a directory the scan uid can traverse (t.TempDir is 0700,
// which only matters when the tests run as root and children drop to
// uid 2000000000).
func worldDir(t *testing.T) string {
	t.Helper()
	d, err := os.MkdirTemp("", "kgc-test-")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(d, 0o755); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(d) })
	return d
}

// childBinary returns a copy of the test binary the scan uid can execute.
func childBinary(t *testing.T) string {
	t.Helper()
	if os.Geteuid() != 0 {
		return os.Args[0]
	}
	dst := filepath.Join(worldDir(t), "child.test")
	b, err := os.ReadFile(os.Args[0])
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dst, b, 0o755); err != nil {
		t.Fatal(err)
	}
	return dst
}

type env struct {
	srv  *Server
	sock string
}

func newServer(t *testing.T, mut func(*Config), childEnv ...string) *env {
	t.Helper()
	tmp := worldDir(t)
	_ = os.Chmod(tmp, 0o1777)
	cfg := Config{
		AllowedPeerUIDs: []uint32{uint32(os.Getuid())},
		MemoryLimit:     512 << 20,
		TmpLimit:        64 << 20,
		TmpDir:          tmp,
		Version:         "test",
		ChildPath:       childBinary(t),
		ChildArgs:       []string{"-test.run=^$"},
		ChildEnv:        append([]string{"KG_SERVER_TEST_CHILD=1"}, childEnv...),
	}
	if mut != nil {
		mut(&cfg)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	s, err := New(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	sock := filepath.Join(worldDir(t), "worker.sock")
	l, err := Listen(sock)
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = s.Serve(ctx, l) }()
	return &env{srv: s, sock: sock}
}

// controller is the fake Controller: connect, send {fd, request}, read.
func (e *env) controller(t *testing.T, req *protocol.Request, fd int) (*protocol.Response, error) {
	t.Helper()
	c, err := net.Dial("unix", e.sock)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	uc := c.(*net.UnixConn)
	if err := protocol.SendRequest(uc, req, fd); err != nil {
		t.Fatal(err)
	}
	_ = uc.SetReadDeadline(time.Now().Add(2 * time.Minute))
	return protocol.ReadResponse(uc, protocol.MaxResponseCeiling)
}

func rootFD(t *testing.T, dir string) int {
	t.Helper()
	fd, err := unix.Open(dir, unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = unix.Close(fd) })
	return fd
}

func write(t *testing.T, path string, data []byte, mode os.FileMode) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, mode); err != nil {
		t.Fatal(err)
	}
}

// alpineRoot is a minimal Alpine root with n apk packages.
func alpineRoot(t *testing.T, n int) string {
	t.Helper()
	root := worldDir(t)
	write(t, filepath.Join(root, "etc/os-release"), []byte("ID=alpine\nVERSION_ID=3.20.3\n"), 0o644)
	var db strings.Builder
	for i := range n {
		fmt.Fprintf(&db, "P:pkg%03d\nV:1.0-r%d\nA:x86_64\nL:MIT\no:pkg%03d\nF:usr/bin\nR:pkg%03d\n\n", i, i, i, i)
		write(t, filepath.Join(root, fmt.Sprintf("usr/bin/pkg%03d", i)), []byte("\x7fELF"), 0o755)
	}
	write(t, filepath.Join(root, "lib/apk/db/installed"), []byte(db.String()), 0o644)
	return root
}

func req(id string) *protocol.Request {
	return &protocol.Request{ProtocolVersion: protocol.Version, Op: protocol.OpScan, ScanID: id, Epoch: 42,
		ContainerStartUnixNanos: time.Now().Add(time.Hour).UnixNano()}
}

func TestScanRoundTrip(t *testing.T) {
	e := newServer(t, nil)
	resp, err := e.controller(t, req("rt-1"), rootFD(t, alpineRoot(t, 3)))
	if err != nil {
		t.Fatal(err)
	}
	if resp.Status != protocol.StatusOK || resp.ScanID != "rt-1" || resp.Epoch != 42 || resp.ProtocolVersion != 1 {
		t.Fatalf("resp %+v", resp)
	}
	if len(resp.Components) != 4 || resp.Components[0].Type != "operating-system" {
		t.Errorf("components %+v", resp.Components)
	}
	if resp.Stats.Attempts != 1 || resp.Stats.CapsModel != e.srv.Model().Name || resp.Stats.SyftVersion == "" ||
		resp.Scanner.Name != "kguardian-cataloger" || resp.Stats.DurationMS <= 0 {
		t.Errorf("stats %+v scanner %+v", resp.Stats, resp.Scanner)
	}
	// Model (ii) is always partial; model (i) on a fully readable root is full.
	want := protocol.CompletenessFull
	if e.srv.Model().Name == "ii" {
		want = protocol.CompletenessPartial
	}
	if resp.Completeness != want {
		t.Errorf("completeness %s %v, want %s", resp.Completeness, resp.PartialReasons, want)
	}
}

func TestPing(t *testing.T) {
	e := newServer(t, nil)
	resp, err := e.controller(t, &protocol.Request{ProtocolVersion: 1, Op: protocol.OpPing, ScanID: "p"}, -1)
	if err != nil || resp.Status != protocol.StatusOK || resp.Stats.CapsModel == "" || resp.Stats.WorkerVersion != "test" {
		t.Fatalf("%+v %v", resp, err)
	}
}

func TestBadRequests(t *testing.T) {
	e := newServer(t, nil)
	root := alpineRoot(t, 1)
	file := filepath.Join(root, "etc/os-release")
	fileFD, err := unix.Open(file, unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = unix.Close(fileFD) }()

	v2 := req("v2")
	v2.ProtocolVersion = 2
	for name, c := range map[string]struct {
		req  *protocol.Request
		fd   int
		want string
	}{
		"version":  {v2, rootFD(t, root), protocol.ReasonUnsupportedProtocol},
		"no fd":    {req("nofd"), -1, protocol.ReasonBadRequest},
		"file fd":  {req("file"), fileFD, protocol.ReasonBadRequest},
		"bad id":   {req("bad id"), rootFD(t, root), protocol.ReasonBadRequest},
		"relative": {func() *protocol.Request { r := req("rel"); r.Submounts = []string{"etc"}; return r }(), rootFD(t, root), protocol.ReasonBadRequest},
	} {
		resp, err := e.controller(t, c.req, c.fd)
		if err != nil || resp.Status != protocol.StatusFailed || resp.Reason != c.want {
			t.Errorf("%s: %+v %v", name, resp, err)
		}
	}
}

func TestTwoFDsRejected(t *testing.T) {
	e := newServer(t, nil)
	root := alpineRoot(t, 1)
	c, err := net.Dial("unix", e.sock)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	body := []byte(`{"protocol_version":1,"op":"scan","scan_id":"x"}`)
	frame := append([]byte{0, 0, 0, byte(len(body))}, body...)
	if _, _, err := c.(*net.UnixConn).WriteMsgUnix(frame, unix.UnixRights(rootFD(t, root), rootFD(t, root)), nil); err != nil {
		t.Fatal(err)
	}
	resp, err := protocol.ReadResponse(c, 1<<20)
	if err != nil || resp.Reason != protocol.ReasonBadRequest {
		t.Fatalf("%+v %v", resp, err)
	}
}

func TestPeerNotAllowed(t *testing.T) {
	e := newServer(t, func(c *Config) { c.AllowedPeerUIDs = []uint32{4242} })
	c, err := net.Dial("unix", e.sock)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	// The worker hangs up at once: the send may already fail, and the read
	// must never produce a response.
	_ = protocol.SendRequest(c.(*net.UnixConn), req("peer"), rootFD(t, alpineRoot(t, 1)))
	_ = c.SetReadDeadline(time.Now().Add(10 * time.Second))
	if resp, err := protocol.ReadResponse(c, 1<<20); err == nil {
		t.Fatalf("a refused peer got a response: %+v", resp)
	}
}

func TestTimeoutKillsTheChild(t *testing.T) {
	e := newServer(t, nil, "KG_TEST_CHILD_SLEEP_MS=60000")
	r := req("slow")
	r.Budgets.ScanTimeoutMS = 1500
	start := time.Now()
	resp, err := e.controller(t, r, rootFD(t, alpineRoot(t, 1)))
	if err != nil {
		t.Fatal(err)
	}
	if resp.Reason != protocol.ReasonTimeout || resp.Stats.Attempts != 1 {
		t.Errorf("%+v", resp)
	}
	if d := time.Since(start); d > 15*time.Second {
		t.Errorf("timeout took %s", d)
	}
}

func TestBusy(t *testing.T) {
	e := newServer(t, nil, "KG_TEST_CHILD_SLEEP_MS=3000")
	root := alpineRoot(t, 1)
	first := make(chan *protocol.Response, 1)
	go func() {
		resp, _ := e.controller(t, req("first"), rootFD(t, root))
		first <- resp
	}()
	time.Sleep(500 * time.Millisecond)
	resp, err := e.controller(t, req("second"), rootFD(t, root))
	if err != nil || resp.Reason != protocol.ReasonBusy || resp.ScanID != "second" {
		t.Fatalf("second: %+v %v", resp, err)
	}
	if r := <-first; r == nil || r.Status != protocol.StatusOK {
		t.Fatalf("first: %+v", r)
	}
}

func TestClosingTheConnectionCancels(t *testing.T) {
	e := newServer(t, nil, "KG_TEST_CHILD_SLEEP_MS=60000")
	c, err := net.Dial("unix", e.sock)
	if err != nil {
		t.Fatal(err)
	}
	if err := protocol.SendRequest(c.(*net.UnixConn), req("cancel"), rootFD(t, alpineRoot(t, 1))); err != nil {
		t.Fatal(err)
	}
	time.Sleep(500 * time.Millisecond)
	_ = c.Close()
	// The worker is free again once the child is gone.
	deadline := time.Now().Add(10 * time.Second)
	for e.srv.busy.Load() {
		if time.Now().After(deadline) {
			t.Fatal("scan still running after the Controller hung up")
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func TestOOMRetriesOSOnlyThenFails(t *testing.T) {
	// A heap cap the Go runtime alone exceeds: both attempts hit it.
	e := newServer(t, func(c *Config) { c.MemoryLimit = 1 << 20 })
	resp, err := e.controller(t, req("oom"), rootFD(t, alpineRoot(t, 2)))
	if err != nil {
		t.Fatal(err)
	}
	if resp.Reason != protocol.ReasonOOM || resp.RetryReason != protocol.ReasonOOM || resp.Stats.Attempts != 2 {
		t.Errorf("%+v", resp)
	}
}

// nestedJar is a Spring Boot style jar whose nested jar is larger than the
// temp budget: Syft must unpack it into its temp dir.
func nestedJar(t *testing.T, path string) {
	t.Helper()
	var inner bytes.Buffer
	zw := zip.NewWriter(&inner)
	w, _ := zw.Create("META-INF/MANIFEST.MF")
	_, _ = io.WriteString(w, "Manifest-Version: 1.0\nImplementation-Title: big\nImplementation-Version: 1.2.3\n")
	w, _ = zw.Create("META-INF/maven/org.example/big/pom.properties")
	_, _ = io.WriteString(w, "groupId=org.example\nartifactId=big\nversion=1.2.3\n")
	w, _ = zw.CreateHeader(&zip.FileHeader{Name: "blob.bin", Method: zip.Store})
	blob := make([]byte, 512<<10)
	_, _ = rand.Read(blob)
	_, _ = w.Write(blob)
	_ = zw.Close()

	var outer bytes.Buffer
	zw = zip.NewWriter(&outer)
	w, _ = zw.Create("META-INF/MANIFEST.MF")
	_, _ = io.WriteString(w, "Manifest-Version: 1.0\nMain-Class: org.springframework.boot.loader.launch.JarLauncher\n")
	w, _ = zw.CreateHeader(&zip.FileHeader{Name: "BOOT-INF/lib/big-1.2.3.jar", Method: zip.Store})
	_, _ = w.Write(inner.Bytes())
	_ = zw.Close()
	write(t, path, outer.Bytes(), 0o644)
}

func TestTempSpaceExhaustedRetriesOSOnly(t *testing.T) {
	root := alpineRoot(t, 2)
	nestedJar(t, filepath.Join(root, "app/app.jar"))
	e := newServer(t, func(c *Config) { c.TmpLimit = 128 << 10 })
	resp, err := e.controller(t, req("enospc"), rootFD(t, root))
	if err != nil {
		t.Fatal(err)
	}
	if resp.Status != protocol.StatusOK || resp.Completeness != protocol.CompletenessOSOnly ||
		resp.RetryReason != protocol.ReasonOOM || resp.Stats.Attempts != 2 {
		t.Fatalf("%s/%s completeness %s retry %q attempts %d: %s %v %+v", resp.Status, resp.Reason, resp.Completeness,
			resp.RetryReason, resp.Stats.Attempts, resp.Message, resp.PartialReasons, resp.Components)
	}
	// Control: with room, the nested jar is found in one attempt.
	e2 := newServer(t, nil)
	resp, err = e2.controller(t, req("room"), rootFD(t, root))
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, c := range resp.Components {
		found = found || (c.Name == "big" && c.Version == "1.2.3")
	}
	if !found || resp.Stats.Attempts != 1 {
		t.Errorf("nested jar not catalogued with enough temp space: %+v", resp.Components)
	}
}

func TestFileBudgetRetriesOSOnly(t *testing.T) {
	e := newServer(t, nil)
	r := req("files")
	r.Budgets.MaxFiles = 12
	resp, err := e.controller(t, r, rootFD(t, alpineRoot(t, 20)))
	if err != nil {
		t.Fatal(err)
	}
	if resp.Status != protocol.StatusOK || resp.Completeness != protocol.CompletenessOSOnly ||
		resp.RetryReason != protocol.ReasonTooManyFiles || resp.Stats.Attempts != 2 {
		t.Errorf("%s/%s %s retry %q: %v", resp.Status, resp.Reason, resp.Completeness, resp.RetryReason, resp.PartialReasons)
	}
}

func TestComponentBudget(t *testing.T) {
	e := newServer(t, nil)
	r := req("comps")
	r.Budgets.MaxComponents = 5
	resp, err := e.controller(t, r, rootFD(t, alpineRoot(t, 20)))
	if err != nil {
		t.Fatal(err)
	}
	if resp.Reason != protocol.ReasonTooManyComponents || resp.RetryReason != protocol.ReasonTooManyComponents || resp.Stats.Attempts != 2 {
		t.Errorf("%+v", resp)
	}
}

func TestNoPackagesFound(t *testing.T) {
	e := newServer(t, nil)
	root := worldDir(t)
	write(t, filepath.Join(root, "etc/os-release"), []byte("ID=alpine\n"), 0o644)
	resp, err := e.controller(t, req("empty"), rootFD(t, root))
	if err != nil || resp.Reason != protocol.ReasonNoPackagesFound {
		t.Fatalf("%+v %v", resp, err)
	}
}

func TestValidateRejectsBadChildOutput(t *testing.T) {
	b := protocol.Budgets{}.Effective()
	good := func() *protocol.Response {
		return &protocol.Response{Status: protocol.StatusOK, Completeness: protocol.CompletenessFull,
			Components: []protocol.Component{{Name: "a", FilePaths: []string{"/bin/a"}}}}
	}
	if err := Validate(good(), b); err != nil {
		t.Fatal(err)
	}
	for name, mut := range map[string]func(r *protocol.Response){
		"status":       func(r *protocol.Response) { r.Status = "maybe" },
		"completeness": func(r *protocol.Response) { r.Completeness = "most" },
		"reason on ok": func(r *protocol.Response) { r.Reason = "oom" },
		"no name":      func(r *protocol.Response) { r.Components[0].Name = "" },
		"long name":    func(r *protocol.Response) { r.Components[0].Name = strings.Repeat("x", 257) },
		"rel path":     func(r *protocol.Response) { r.Components[0].FilePaths = []string{"bin/a"} },
		"dotdot path":  func(r *protocol.Response) { r.Components[0].FilePaths = []string{"/bin/../../etc/shadow"} },
		"class":        func(r *protocol.Response) { r.Components[0].Class = "weird" },
		"partial":      func(r *protocol.Response) { r.PartialReasons = []string{"because"} },
		"failed with components": func(r *protocol.Response) {
			r.Status, r.Reason, r.Completeness = protocol.StatusFailed, protocol.ReasonOOM, ""
		},
		"unknown reason": func(r *protocol.Response) {
			r.Status, r.Reason, r.Completeness, r.Components = protocol.StatusFailed, "sad", "", nil
		},
		"too many paths": func(r *protocol.Response) {
			for i := range 5000 {
				r.Components[0].FilePaths = append(r.Components[0].FilePaths, fmt.Sprintf("/p/%d", i))
			}
		},
	} {
		r := good()
		mut(r)
		if err := Validate(r, b); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// childProcesses lists live processes started from the child binary.
func childProcesses(t *testing.T, bin string) []string {
	t.Helper()
	ents, _ := os.ReadDir("/proc")
	var out []string
	for _, e := range ents {
		if _, err := strconv.Atoi(e.Name()); err != nil {
			continue
		}
		cmd, err := os.ReadFile("/proc/" + e.Name() + "/cmdline")
		if err != nil || !strings.HasPrefix(string(cmd), bin+"\x00") || !strings.Contains(string(cmd), "scan-child") {
			continue
		}
		// Zombies still waiting to be reaped are not running.
		if st, err := os.ReadFile("/proc/" + e.Name() + "/stat"); err == nil && strings.Contains(string(st), ") Z ") {
			continue
		}
		out = append(out, e.Name())
	}
	return out
}

// A deadline that fires right after the child starts must still kill it
// (the kill may run before Start has returned, and must never fall back
// to a plain kill that a uid-0 parent without CAP_KILL cannot send).
func TestImmediateDeadlineKillsTheChild(t *testing.T) {
	e := newServer(t, nil, "KG_TEST_CHILD_SLEEP_MS=60000")
	r := req("instant")
	r.Budgets.ScanTimeoutMS = 1
	start := time.Now()
	resp, err := e.controller(t, r, rootFD(t, alpineRoot(t, 1)))
	if err != nil {
		t.Fatal(err)
	}
	if resp.Reason != protocol.ReasonTimeout || time.Since(start) > 15*time.Second {
		t.Fatalf("%s after %s", resp.Reason, time.Since(start))
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		left := childProcesses(t, e.srv.cfg.ChildPath)
		if len(left) == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("scan children still running after the deadline: %v", left)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func TestRuntimeOutOfMemoryAbortIsOOM(t *testing.T) {
	head := "runtime: out of memory: cannot allocate 1073741824-byte block (4194304 in use)\nfatal error: out of memory\n"
	buf := &stderrBuffer{headMax: 4 * 1024, tailMax: 12 * 1024}
	_, _ = buf.Write([]byte(head + strings.Repeat("goroutine 1 [running]:\n\tmain.go:1\n", 5000)))
	r := childResult{stderr: buf.String(), state: &os.ProcessState{}}
	if !oomExit(r) {
		t.Fatal("the headline of a long crash dump was lost")
	}
	if l := crashLine(buf.String()); !strings.Contains(l, "out of memory") {
		t.Errorf("crash line %q", l)
	}
}
