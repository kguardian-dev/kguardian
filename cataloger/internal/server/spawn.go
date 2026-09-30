package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strconv"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	"github.com/kguardian-dev/kguardian/cataloger/internal/child"
	"github.com/kguardian-dev/kguardian/cataloger/internal/protocol"
)

// ScanUID is the uid and gid every scan child runs as (and the only
// identity that ever parses image content).
const ScanUID = 2000000000

// Model is the capability model the startup probe established.
type Model struct {
	// Name: "i" (child has CAP_DAC_READ_SEARCH as ambient) or "ii" (no
	// capabilities; unreadable files are counted, completeness partial).
	Name string
	// SetUID: the child is started as ScanUID (the parent is uid 0).
	SetUID bool
	// Ambient: CAP_DAC_READ_SEARCH is raised in the child's ambient set.
	Ambient bool
	// Why explains the choice, for the startup log.
	Why string
}

// stderrBuffer keeps the first head and the last tail bytes of the
// child's stderr. A Go crash puts its headline ("fatal error: runtime: out
// of memory", "panic: ...") first and goroutine dumps after it, so both
// ends matter and the middle does not.
type stderrBuffer struct {
	mu         sync.Mutex
	head, tail []byte
	headMax    int
	tailMax    int
	dropped    bool
}

func (t *stderrBuffer) Write(p []byte) (int, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	n := len(p)
	if room := t.headMax - len(t.head); room > 0 {
		k := min(room, len(p))
		t.head = append(t.head, p[:k]...)
		p = p[k:]
	}
	t.tail = append(t.tail, p...)
	if len(t.tail) > t.tailMax {
		t.tail = append([]byte(nil), t.tail[len(t.tail)-t.tailMax:]...)
		t.dropped = true
	}
	return n, nil
}

func (t *stderrBuffer) String() string {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.dropped {
		return string(t.head) + "\n[...]\n" + string(t.tail)
	}
	return string(t.head) + string(t.tail)
}

// childResult is one child run.
type childResult struct {
	payload  []byte // the response frame, nil if none
	state    *os.ProcessState
	killed   bool // we SIGKILLed it (deadline or cancel)
	stderr   string
	startErr error
}

// command builds the child process: only the root fd and the socketpair
// end are passed (plus stdio: /dev/null in and out, stderr to a bounded
// buffer), with a minimal environment.
func (s *Server) command(ctx context.Context, arg string, m Model, root *os.File, peer *os.File, stderr io.Writer) *exec.Cmd {
	cmd := exec.CommandContext(ctx, s.cfg.ChildPath, append(append([]string{}, s.cfg.ChildArgs...), arg)...)
	cmd.Env = []string{
		"GOMAXPROCS=1",
		"GOMEMLIMIT=" + strconv.FormatInt(s.cfg.MemoryLimit*85/100, 10),
		"HOME=/nonexistent",
		child.EnvCapsModel + "=" + m.Name,
		child.EnvMemoryLimit + "=" + strconv.FormatInt(s.cfg.MemoryLimit, 10),
		child.EnvTmpLimit + "=" + strconv.FormatInt(s.cfg.TmpLimit, 10),
		child.EnvTmpRoot + "=" + s.cfg.TmpDir,
		child.EnvVersion + "=" + s.cfg.Version,
	}
	if s.cfg.Verbose {
		cmd.Env = append(cmd.Env, child.EnvVerbose+"=1")
	}
	cmd.Env = append(cmd.Env, s.cfg.ChildEnv...)
	cmd.ExtraFiles = []*os.File{root, peer}
	cmd.Stderr = stderr
	// Setpgid: the child leads its own process group, which the kill
	// covers too. Pdeathsig fires when the forking thread exits, not the
	// process (a Linux rule); the child also dies with the parent's socket
	// and deadline, so this is a backstop for a crashed parent.
	attr := &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL, Setpgid: true}
	if m.SetUID {
		attr.Credential = &syscall.Credential{Uid: ScanUID, Gid: ScanUID, Groups: []uint32{}}
	}
	if m.Ambient {
		attr.AmbientCaps = []uintptr{unix.CAP_DAC_READ_SEARCH}
	}
	cmd.SysProcAttr = attr
	cmd.WaitDelay = 5 * time.Second
	return cmd
}

// run starts one child, sends it msg (if any) and reads back one frame of
// at most max bytes.
func (s *Server) run(ctx context.Context, arg string, m Model, root *os.File, msg any, max int) childResult {
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return childResult{startErr: err}
	}
	mine := os.NewFile(uintptr(fds[0]), "child-conn")
	peer := os.NewFile(uintptr(fds[1]), "child-conn-peer")
	defer func() { _ = mine.Close() }()

	if root == nil {
		root, _ = os.Open(os.DevNull)
		defer func() { _ = root.Close() }()
	}
	stderr := &stderrBuffer{headMax: 4 * 1024, tailMax: 12 * 1024}
	cmd := s.command(ctx, arg, m, root, peer, stderr)
	uid := -1
	if m.SetUID {
		uid = ScanUID
	}
	killer := newChildKiller(uid, func() int {
		if cmd.Process == nil {
			return 0
		}
		return cmd.Process.Pid
	})
	defer killer.close()
	cmd.Cancel = killer.kill
	err = cmd.Start()
	_ = peer.Close()
	if err != nil {
		return childResult{startErr: err}
	}
	// Not reaped until Wait, so the pid still names our child here.
	killer.started()

	var res childResult
	done := make(chan struct{})
	go func() {
		defer close(done)
		if msg != nil {
			if err := protocol.WriteJSON(mine, msg); err != nil {
				return
			}
		}
		b, err := protocol.ReadFrame(mine, max)
		if err == nil {
			res.payload = b
		}
		// Drain: a child writing more than one frame is invalid.
		if n, _ := io.Copy(io.Discard, io.LimitReader(mine, 1)); n > 0 {
			res.payload = nil
		}
	}()
	werr := cmd.Wait()
	// The child is gone: its end is closed, so the reader finishes.
	_ = mine.SetDeadline(time.Now().Add(time.Second))
	<-done
	res.state = cmd.ProcessState
	res.killed = ctx.Err() != nil
	res.stderr = stderr.String()
	if res.state == nil && werr != nil {
		res.startErr = werr
	}
	return res
}

// oomExit reports whether the child died of memory exhaustion: a SIGKILL
// it did not get from us (the cgroup OOM killer), or the Go runtime's own
// out-of-memory abort.
func oomExit(r childResult) bool {
	if r.state == nil {
		return false
	}
	if ws, ok := r.state.Sys().(syscall.WaitStatus); ok && ws.Signaled() && ws.Signal() == syscall.SIGKILL && !r.killed {
		return true
	}
	return bytes.Contains([]byte(r.stderr), []byte("out of memory")) || bytes.Contains([]byte(r.stderr), []byte("cannot allocate memory"))
}

// maxRSS is the child's peak resident set in bytes.
func maxRSS(st *os.ProcessState) int64 {
	if st == nil {
		return 0
	}
	if ru, ok := st.SysUsage().(*syscall.Rusage); ok {
		return ru.Maxrss * 1024
	}
	return 0
}

// probeModel establishes the capability model once at startup by starting
// a probe child the same way scans are started and reading back its
// identity and capabilities.
func (s *Server) probeModel(ctx context.Context) (Model, error) {
	try := func(m Model) (child.ProbeResult, error) {
		pctx, cancel := context.WithTimeout(ctx, 30*time.Second)
		defer cancel()
		r := s.run(pctx, "probe-caps", m, nil, nil, 4096)
		if r.startErr != nil {
			return child.ProbeResult{}, r.startErr
		}
		if r.payload == nil {
			return child.ProbeResult{}, fmt.Errorf("probe child gave no answer: %s", r.stderr)
		}
		var p child.ProbeResult
		if err := json.Unmarshal(r.payload, &p); err != nil {
			return p, err
		}
		return p, nil
	}
	if os.Getuid() != 0 {
		// Already unprivileged (tests, or a pod run as non-root): no uid
		// change and no ambient capabilities are possible.
		p, err := try(Model{Name: "ii"})
		if err != nil {
			return Model{}, err
		}
		if p.Caps.Effective != 0 {
			return Model{}, fmt.Errorf("probe child has capabilities %s without a uid change", capNames(p.Caps.Effective))
		}
		return Model{Name: "ii", Why: fmt.Sprintf("worker runs as uid %d, not 0: no uid change, no CAP_DAC_READ_SEARCH", os.Getuid())}, nil
	}
	p, err := try(Model{Name: "i", SetUID: true, Ambient: true})
	if err == nil && p.UID == ScanUID && p.Caps.Effective == capDRS {
		return Model{Name: "i", SetUID: true, Ambient: true, Why: "ambient CAP_DAC_READ_SEARCH holds in the scan child"}, nil
	}
	why := "ambient CAP_DAC_READ_SEARCH unavailable"
	if err != nil {
		why += ": " + err.Error()
	} else {
		why += fmt.Sprintf(": child uid %d caps %s", p.UID, capNames(p.Caps.Effective))
	}
	p, err2 := try(Model{Name: "ii", SetUID: true})
	if err2 != nil {
		if errors.Is(err2, syscall.EPERM) {
			return Model{}, fmt.Errorf("cannot start the scan child as uid %d (needs CAP_SETUID and CAP_SETGID); refusing to parse image content as uid 0: %w", ScanUID, err2)
		}
		return Model{}, err2
	}
	if p.UID != ScanUID || p.Caps.Effective != 0 {
		return Model{}, fmt.Errorf("model (ii) probe child is uid %d with caps %s", p.UID, capNames(p.Caps.Effective))
	}
	return Model{Name: "ii", SetUID: true, Why: why}, nil
}
