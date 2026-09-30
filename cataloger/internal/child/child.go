// Package child is the per-scan process: re-executed by the worker parent
// as uid 2000000000 with (model (i)) CAP_DAC_READ_SEARCH as its only
// capability, it confines itself before reading anything, scans the root
// it was handed on fd 3, writes one response frame to fd 4 and exits.
package child

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"runtime/metrics"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/unix"

	"github.com/kguardian-dev/kguardian/cataloger/internal/protocol"
	"github.com/kguardian-dev/kguardian/cataloger/internal/sandbox"
	"github.com/kguardian-dev/kguardian/cataloger/internal/scan"
)

// Descriptors the parent passes (os/exec ExtraFiles start at 3).
const (
	FDRoot = 3 // the container root (O_PATH directory)
	FDConn = 4 // socketpair to the parent: request in, response out
)

// Environment the parent sets for the child.
const (
	EnvCapsModel   = "KG_CATALOG_CAPS_MODEL"   // "i" or "ii"
	EnvMemoryLimit = "KG_CATALOG_MEMORY_LIMIT" // hard heap cap, bytes
	EnvTmpLimit    = "KG_CATALOG_TMP_LIMIT"    // temp space cap, bytes
	EnvTmpRoot     = "KG_CATALOG_TMP_ROOT"     // where the scan's temp dir goes
	EnvVersion     = "KG_CATALOG_VERSION"
	EnvVerbose     = "KG_CATALOG_VERBOSE"
)

// ProbeResult is what "probe-caps" reports to the parent.
type ProbeResult struct {
	UID  int          `json:"uid"`
	GID  int          `json:"gid"`
	Caps sandbox.Caps `json:"caps"`
	// FDs maps each descriptor the child inherited to its /proc target
	// (read before anything is closed), so tests can prove nothing but
	// the intended descriptors reaches a child.
	FDs map[int]string `json:"fds"`
}

// Probe reports the child's identity and capabilities on fd 4 (the
// parent's startup check of the capability model).
func Probe() int {
	caps, err := sandbox.CurrentCaps()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	fds := map[int]string{}
	if list, err := sandbox.OpenFDs(); err == nil {
		for _, fd := range list {
			target, _ := os.Readlink("/proc/self/fd/" + strconv.Itoa(fd))
			fds[fd] = target
		}
	}
	conn := os.NewFile(FDConn, "conn")
	if err := protocol.WriteJSON(conn, ProbeResult{UID: os.Getuid(), GID: os.Getgid(), Caps: caps, FDs: fds}); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	return 0
}

func envInt(k string) int64 {
	v, _ := strconv.ParseInt(os.Getenv(k), 10, 64)
	return v
}

// writer sends exactly one response.
type writer struct {
	once sync.Once
	w    io.Writer
}

func (w *writer) send(resp *protocol.Response) {
	w.once.Do(func() {
		if err := protocol.WriteJSON(w.w, resp); err != nil {
			fmt.Fprintln(os.Stderr, "write response:", err)
		}
	})
}

// Main runs one scan. Order matters: descriptors, limits and priorities
// first, then the capability check and seccomp, and only then is any
// byte of the container read.
func Main() int {
	memLimit := envInt(EnvMemoryLimit)
	tmpLimit := envInt(EnvTmpLimit)
	soft := memLimit * 85 / 100
	if err := sandbox.Harden(sandbox.Limits{KeepFDs: FDConn + 1, MemoryLimit: soft, MaxFileSize: tmpLimit,
		OnFileTooLarge: func() { scan.NoSpaceSeen.Store(true) }}); err != nil {
		fmt.Fprintln(os.Stderr, "harden:", err)
		return 3
	}
	conn := os.NewFile(FDConn, "conn")
	out := &writer{w: conn}

	payload, err := protocol.ReadFrame(conn, protocol.MaxRequestBytes)
	if err != nil {
		fmt.Fprintln(os.Stderr, "read request:", err)
		return 3
	}
	var req protocol.Request
	if err := json.Unmarshal(payload, &req); err != nil {
		fmt.Fprintln(os.Stderr, "decode request:", err)
		return 3
	}
	model := os.Getenv(EnvCapsModel)
	if err := checkCaps(model); err != nil {
		out.send(protocol.Failed(&req, protocol.ReasonCapsUnavailable, err.Error()))
		return 0
	}
	if err := sandbox.InstallSeccomp(); err != nil {
		out.send(protocol.Failed(&req, protocol.ReasonError, err.Error()))
		return 0
	}
	if err := sandbox.SelfCheckSeccomp(); err != nil {
		out.send(protocol.Failed(&req, protocol.ReasonError, err.Error()))
		return 0
	}
	scan.InstallLogger(os.Stderr, os.Getenv(EnvVerbose) == "1")

	tmpRoot := os.Getenv(EnvTmpRoot)
	if tmpRoot == "" {
		tmpRoot = os.TempDir()
	}
	tmp, err := os.MkdirTemp(tmpRoot, "kg-scan-")
	if err != nil {
		out.send(protocol.Failed(&req, protocol.ReasonError, "temp dir: "+err.Error()))
		return 0
	}
	defer func() { _ = os.RemoveAll(tmp) }()
	_ = os.Setenv("TMPDIR", tmp)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go watch(ctx, &req, out, memLimit, tmp, tmpLimit)

	resp := scan.Run(ctx, FDRoot, scan.Options{
		Profile:             req.Profile,
		Budgets:             req.Budgets,
		ContainerStartNanos: req.ContainerStartUnixNanos,
		Submounts:           req.Submounts,
		CapsModel:           model,
		Version:             os.Getenv(EnvVersion),
	})
	out.send(resp)
	return 0
}

// checkCaps verifies the capability model the parent established at
// startup still holds in this process: exactly CAP_DAC_READ_SEARCH under
// model (i), nothing under model (ii), and never uid 0.
func checkCaps(model string) error {
	if os.Getuid() == 0 || os.Geteuid() == 0 {
		return fmt.Errorf("scan child runs as uid 0")
	}
	c, err := sandbox.CurrentCaps()
	if err != nil {
		return err
	}
	want := uint64(0)
	if model == "i" {
		want = sandbox.ChildModelI
	}
	if c.Effective != want || c.Permitted != want {
		return fmt.Errorf("capabilities effective=%s permitted=%s, want %s (model %s)",
			sandbox.Names(c.Effective), sandbox.Names(c.Permitted), sandbox.Names(want), model)
	}
	return nil
}

// watch enforces the memory and temp-space caps. Crossing either writes
// an oom response and exits at once: Syft cannot be interrupted, and a
// heap that keeps growing would otherwise meet the cgroup OOM killer.
func watch(ctx context.Context, req *protocol.Request, out *writer, memLimit int64, tmp string, tmpLimit int64) {
	samples := []metrics.Sample{
		{Name: "/memory/classes/total:bytes"},
		{Name: "/memory/classes/heap/released:bytes"},
	}
	t := time.NewTicker(200 * time.Millisecond)
	defer t.Stop()
	for i := 0; ; i++ {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		if memLimit > 0 {
			metrics.Read(samples)
			used := int64(samples[0].Value.Uint64() - samples[1].Value.Uint64())
			if used > memLimit {
				out.send(protocol.Failed(req, protocol.ReasonOOM, fmt.Sprintf("heap %d bytes over the %d byte limit", used, memLimit)))
				os.Exit(0)
			}
		}
		if tmpLimit > 0 && i%2 == 0 {
			if used := dirBytes(tmp, 0); used > tmpLimit || scan.NoSpaceSeen.Load() {
				out.send(protocol.Failed(req, protocol.ReasonOOM, fmt.Sprintf("temp space %d bytes over the %d byte limit", used, tmpLimit)))
				os.Exit(0)
			}
			var sfs unix.Statfs_t
			if unix.Statfs(tmp, &sfs) == nil && int64(sfs.Bavail)*sfs.Bsize < 1<<20 {
				out.send(protocol.Failed(req, protocol.ReasonOOM, "temp filesystem full"))
				os.Exit(0)
			}
		}
	}
}

// dirBytes sums allocated bytes under dir.
func dirBytes(dir string, depth int) int64 {
	if depth > 64 {
		return 0
	}
	ents, err := os.ReadDir(dir)
	if err != nil {
		return 0
	}
	var n int64
	for _, e := range ents {
		p := dir + "/" + e.Name()
		if e.IsDir() {
			n += dirBytes(p, depth+1)
			continue
		}
		var st unix.Stat_t
		if unix.Lstat(p, &st) == nil {
			n += st.Blocks * 512
		}
	}
	return n
}

// CleanTmp removes scan temp dirs left by children that were killed. It
// runs as the scan uid, so it can only remove the scan uid's own files.
func CleanTmp() int {
	root := os.Getenv(EnvTmpRoot)
	if root == "" {
		root = os.TempDir()
	}
	ents, err := os.ReadDir(root)
	if err != nil {
		return 0
	}
	for _, e := range ents {
		if e.IsDir() && strings.HasPrefix(e.Name(), "kg-scan-") {
			_ = os.RemoveAll(root + "/" + e.Name())
		}
	}
	return 0
}
